import React from 'react';
import {MultiSelect} from '@blueprintjs/select';
import {Button, MenuItem} from '@blueprintjs/core';
import {css, StyleSheet} from 'aphrodite';
import PropTypes from 'prop-types';
import {TagStore} from '../../../data/resource/tag'

class TagEditor extends React.PureComponent {
    constructor(props) {
        super(props);
        this.state = {
            selected: props.tags,
            tags: []
        };
        this._onItemSelect = this._onItemSelect.bind(this);
        this._isTagSelected = this._isTagSelected.bind(this);
        this._itemRenderer = this._itemRenderer.bind(this);
        this._getTagIndex = this._getTagIndex.bind(this);
        this._handleTagRemove = this._handleTagRemove.bind(this);
        this._handleClear = this._handleClear.bind(this);
        this._callUpdateCallback = this._callUpdateCallback.bind(this);
    }

    componentDidMount() {
        TagStore.getAll().then((e) => {
            e = e.map((item) => {
                return {id: item.id, name: item.name, description: item.description}
            });
            let toAdd = [];
            e = e.filter(item => {
                let result = true;
                this.state.selected.forEach((stateItem) => {
                    console.log(stateItem, item);
                    if (item.id === stateItem.id) {
                        console.log('removing item');
                        result = false;
                        toAdd.push(stateItem);
                    }
                });
                return result;
            });
            e.push(...toAdd);
            console.log(e, this.props.tags);
            this.setState({
                tags: e
            });
        });
    }

    render() {
        const clearButton = this.state.selected.length > 0 ?
            <Button icon="cross" minimal={true} onClick={this._handleClear}/> : null;

        return (
            <MultiSelect
                className={css(styles.input) + ' ' + this.props.className}
                items={this.state.tags}
                itemRenderer={this._itemRenderer}
                itemPredicate={this._itemPredicate}
                onItemSelect={this._onItemSelect}
                tagRenderer={this._tagRenderer}
                popOverProps={{
                    className: this.props.className,
                    targetClassName: this.props.className,
                    popoverClassName: this.props.className
                }}
                tagInputProps={{
                    tagProps: {minimal: true},
                    onRemove: this._handleTagRemove,
                    rightElement: clearButton,
                    fill: true
                }}
                noResults={<MenuItem disabled={true} text="No results."/>}
                selectedItems={this.state.selected}
            />
        );
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
                label={tag.name}
                onClick={handleClick}
                icon={this._isTagSelected(tag) ? 'tick' : 'blank'}
                text={`${tag.description.substring(0, 50) + '...'}`}
                shouldDismissPopover={false}
            />
        );
    }

    _handleClear() {
        this.setState({selected: []});
        this._callUpdateCallback();
    }

    _callUpdateCallback() {
        this.props.onSelectedChange(this.state.selected);
    }

    _isTagSelected(tag) {
        return this._getTagIndex(tag) !== -1;
    }

    _itemPredicate(query, item) {
        return item.name.includes(query);
    }

    _getTagIndex(tag) {
        return this.state.selected.indexOf(tag);
    }

    _handleTagRemove(index) {
        let selected = this.state.selected;
        selected.splice(index, 1);
        this.setState({selected});
        this._callUpdateCallback();
    }

    _onItemSelect(item) {
        if (!this._isTagSelected(item)) {
            this.setState({selected: [...this.state.selected, item]});
        } else {
            this._handleTagRemove(this._getTagIndex(item));
        }
        this._callUpdateCallback();
    }
}

const styles = StyleSheet.create({
    input: {}
});

TagEditor.propTypes = {
    onSelectedChange: PropTypes.func.isRequired,
    tags: PropTypes.array.isRequired,
    className: PropTypes.string
};

export default TagEditor;