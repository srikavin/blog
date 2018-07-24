import React, {Fragment} from 'react';
import {MultiSelect} from '@blueprintjs/select';
import {Alert, Button, FormGroup, Input, Intent, MenuItem, Position, Toaster} from '@blueprintjs/core';
import {css, StyleSheet} from 'aphrodite';
import PropTypes from 'prop-types';
import {TagStore} from '../../../data/resource/tag'
import isEqual from 'react-fast-compare';
import * as IconNames from '@blueprintjs/icons/lib/esm/generated/iconNames';

const TagToaster = Toaster.create({
    className: 'recipe-toaster',
    position: Position.TOP
});

class TagEditor extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selected: props.tags,
            tags: [],
            alertOpen: false,
            query: '',
            newTagName: ''
        };
        this._onItemSelect = this._onItemSelect.bind(this);
        this._isTagSelected = this._isTagSelected.bind(this);
        this._itemRenderer = this._itemRenderer.bind(this);
        this._itemPredicate = this._itemPredicate.bind(this);
        this._getTagIndex = this._getTagIndex.bind(this);
        this._addTag = this._addTag.bind(this);
        this._handleTagRemove = this._handleTagRemove.bind(this);
        this._handleClear = this._handleClear.bind(this);
        this._addTagChange = this._addTagChange.bind(this);
        this._callUpdateCallback = this._callUpdateCallback.bind(this);
        this._addTagConfirm = this._addTagConfirm.bind(this);
        this._addTagCancel = this._addTagCancel.bind(this);
    }

    shouldComponentUpdate(nextProps, nextState, nextContext) {
        return nextState.selected !== this.state.selected ||
            nextState !== this.state ||
            !isEqual(this.props, nextProps);
    }

    componentDidMount() {
        TagStore.getAll().then((e) => {
            e = e.map((item) => {
                return {id: item.id, name: item.name}
            });
            let toAdd = [];
            e = e.filter(item => {
                let result = true;
                this.state.selected.forEach((stateItem) => {
                    if (item.id === stateItem.id) {
                        result = false;
                        toAdd.push(stateItem);
                    }
                });
                return result;
            });
            e.push(...toAdd);
            this.setState({
                tags: e
            });
        });
    }

    render() {
        const clearButton = this.state.selected.length > 0 ?
            <Button icon="cross" minimal={true} onClick={this._handleClear}/> : null;

        return (
            <Fragment>
                <MultiSelect
                    className={css(styles.input) + ' ' + this.props.className}
                    items={this.state.tags}
                    itemRenderer={this._itemRenderer}
                    itemPredicate={this._itemPredicate}
                    onItemSelect={this._onItemSelect}
                    tagRenderer={this._tagRenderer}
                    popoverProps={{
                        minimal: true
                    }}
                    tagInputProps={{
                        onRemove: this._handleTagRemove,
                        rightElement: clearButton,
                        fill: true
                    }}
                    resetOnSelect={true}
                    noResults={<MenuItem shouldDismissPopover={false}
                                         onClick={this.props.addTags ? this._addTag : undefined}
                                         text={`No results. ${this.props.addTags ? `Add ${this.state.query}?` : ''}`}/>}
                    selectedItems={this.state.selected}
                />
                {this._getAlert()}
            </Fragment>
        );
    }

    _getAlert() {
        return (
            <Alert isOpen={this.state.alertOpen} onConfirm={this._addTagConfirm} confirmButtonText="Add Tag"
                   onCancel={this._addTagCancel} cancelButtonText={'Cancel'}>
                <FormGroup label="Tag Name">
                    <input value={this.state.newTagName} onChange={this._addTagChange}/>
                </FormGroup>
            </Alert>
        );
    }

    _addTag() {
        this.setState({
            alertOpen: true,
            newTagName: this.state.query
        });
    }

    _addTagCancel() {
        this.setState({
            alertOpen: false
        });
    }

    _addTagChange(e) {
        this.setState({
            newTagName: e.target.value
        })
    }

    _addTagConfirm() {
        TagStore.add({name: this.state.newTagName})
            .then(e => {
                this.setState({
                    tags: [...this.state.tags, e],
                    alertOpen: false
                });
                TagToaster.show({
                    message: 'Created Tag successfully',
                    intent: Intent.SUCCESS,
                    icon: IconNames.TICK
                })
            }).catch(err => {
            TagToaster.show({
                message: 'Failed to add tag. Error was logged to console.',
                intent: Intent.DANGER,
                icon: IconNames.CROSS
            });
            console.error(err);
        })
    }

    _tagRenderer(tag) {
        return tag.name;
    }

    _itemRenderer(tag, {modifiers, handleClick}) {
        if (!modifiers.matchesPredicate) {
            return null;
        }
        return (
            <MenuItem
                active={modifiers.active}
                key={tag.id}
                label={tag.id}
                onClick={handleClick}
                icon={this._isTagSelected(tag) ? 'tick' : 'blank'}
                text={tag.name}
                shouldDismissPopover={false}
            />
        );
    }

    _handleClear() {
        let selected = [];
        this.setState({selected});
        this._callUpdateCallback(selected);
    }

    _callUpdateCallback(selected) {
        this.props.onSelectedChange(selected);
    }

    _isTagSelected(tag) {
        return this._getTagIndex(tag) !== -1;
    }

    _itemPredicate(query, item) {
        this.setState({query});
        return item.name.includes(query);
    }

    _getTagIndex(tag) {
        return this.state.selected.indexOf(tag);
    }

    _handleTagRemove(index) {
        let selected = this.state.selected;
        selected.splice(index, 1);
        this.setState({selected});
        this._callUpdateCallback(selected);
    }

    _onItemSelect(item) {
        if (!this._isTagSelected(item)) {
            let selected = [...this.state.selected, item];
            this.setState({selected});
            this._callUpdateCallback(selected);
        } else {
            this._handleTagRemove(this._getTagIndex(item));
        }
    }
}

const styles = StyleSheet.create({
    input: {}
});

TagEditor.propTypes = {
    onSelectedChange: PropTypes.func.isRequired,
    tags: PropTypes.array.isRequired,
    className: PropTypes.string,
    addTags: PropTypes.bool
};

export default TagEditor;