import React, {Component, Fragment} from 'react';
import PropTypes from 'prop-types';

import CrudList from '../CrudList/CrudList';
import {Redirect} from 'react-router-dom';
import {TagStore} from '../../../../data/resource/tag'

import styles from './TagCrudList.module.css'
import {Alert, InputGroup, Intent, Tag} from '@blueprintjs/core';

class PostCrudList extends Component {
    constructor(props) {
        super(props);
        this.onDelete = this.onDelete.bind(this);
        this.onEdit = this.onEdit.bind(this);
        this.onView = this.onView.bind(this);
        this.onCreate = this.onCreate.bind(this);
        this.handleDisplay = this.handleDisplay.bind(this);

        this.state = {
            showContent: [],
            newTagName: ''
        };
    }

    onDelete(tag) {
        TagStore.delete(tag.id).then(() => {
            let tags = this.props.items;
            tags = tags.filter((e) => {
                return e.id !== tag.id;
            });
            this.props.updateItems(tags);
        });
    }

    onView(tag) {
        this.setState(prevState => {
            let shows = [...prevState.showContent];

            let index = shows.indexOf(tag.id);

            if (index === -1) {
                shows.push(tag.id);
            } else {
                shows.splice(index, 1);
            }

            return {showContent: shows};
        });
    }

    onEdit(tag) {
        this.setState({
            alert: 'edit',
            alertOpen: true,
            editID: tag.id
        })
    }

    onCreate() {
        this.setState({
            alert: 'create',
            alertOpen: true
        })
    }

    editItem() {
        this.setState({
            alertOpen: false
        });

        TagStore.updateTag(this.state.editID, {
            name: this.state.newTagName
        }).then(updated => {
            let tags = this.props.items;
            tags = tags.filter((e) => {
                return e.id !== updated.id;
            });

            console.log(tags);

            this.props.updateItems([...tags, updated]);
        })
    }

    createItem() {
        this.setState({
            alertOpen: false
        });

        TagStore.add({
            name: this.state.newTagName
        }).then(e => {
            this.props.updateItems([...this.props.items, e]);
        })
    }

    handleDisplay(tag) {
        let ret = (
            <h2 className={styles.tagHeader}>{tag.name}</h2>
        );

        if (this.state.showContent.includes(tag.id)) {
            ret = (
                <Fragment>
                    {ret}
                    <Tag interactive={true} minimal={true}>{tag.name}</Tag>
                </Fragment>
            )
        }
        return ret;
    }

    render() {
        let alert = (
            <Alert isOpen={this.state.alertOpen}
                   onConfirm={() => this.state.alert === 'create' ? this.createItem() : this.editItem()}
                   intent={Intent.PRIMARY}
                   confirmButtonText={'Create'}
                   cancelButtonText={'Cancel'}
                   onCancel={() => this.setState({alertOpen: false})}>
                Enter tag name to <b>{this.state.alert}</b>
                <InputGroup placeholder={'Tag Name'}
                            value={this.state.newTagName}
                            onChange={(e) => this.setState({newTagName: e.target.value})}
                />
            </Alert>
        );
        if (this.state.redirect) {
            return <Redirect push={true} to={this.state.redirect}/>
        }
        return (
            <Fragment>
                {alert}
                <CrudList
                    items={this.props.items}
                    onDelete={this.onDelete}
                    onEdit={this.onEdit}
                    onView={this.onView}
                    onCreate={this.onCreate}
                    display={this.handleDisplay}
                />
            </Fragment>
        );
    }
}

PostCrudList.propTypes = {
    items: PropTypes.array.isRequired,
    updateItems: PropTypes.func.isRequired
};

export default PostCrudList;