import React, {Component, Fragment} from 'react';
import PropTypes from 'prop-types';

import {PostStore} from '../../../../../data/resource/post';
import CrudList from '../../CrudList/CrudList';
import PostHeader from '../../../../Post/PostHeader/PostHeader';
import {Redirect} from 'react-router-dom';
import PostContent from '../../../../Post/PostContent/PostContent';

class PostCrudList extends Component {
    constructor(props) {
        super(props);
        this.onDelete = this.onDelete.bind(this);
        this.onEdit = this.onEdit.bind(this);
        this.onView = this.onView.bind(this);
        this.onCreate = this.onCreate.bind(this);
        this.handleDisplay = this.handleDisplay.bind(this);

        this.state = {
            showContent: []
        };
    }

    onDelete(post) {
        PostStore.delete(post.id).then(() => {
            let posts = this.props.items;
            posts = posts.filter((e) => {
                return e.id !== post.id;
            });
            this.props.updateItems(posts);
        });
    }

    onView(post) {
        this.setState(prevState => {
            let shows = [...prevState.showContent];

            let index = shows.indexOf(post.id);

            if (index === -1) {
                shows.push(post.id);
            } else {
                shows.splice(index, 1);
            }

            return {showContent: shows};
            // redirect: `/blog/posts/${post.slug}`
        });
    }

    onEdit(post) {
        this.setState({
            redirect: `/admin/edit/${post.id}`
        });
    }

    onCreate() {
        this.setState({
            redirect: '/admin/posts/new'
        });
    }

    handleDisplay(post) {
        let ret = (
            <PostHeader title={post.title}
                        modifiedTime={post.updatedAt}
                        createdTime={post.createdAt}
                        tags={post.tags}
                        author={post.author}
            />
        );
        if (this.state.showContent.includes(post.id)) {
            ret = (
                <Fragment>
                    {ret}
                    <PostContent content={post.contents}/>
                </Fragment>
            )
        }
        return ret;
    }

    render() {
        if (this.state.redirect) {
            return <Redirect push={true} to={this.state.redirect}/>
        }
        return (
            <CrudList
                items={this.props.items}
                onDelete={this.onDelete}
                onEdit={this.onEdit}
                onView={this.onView}
                onCreate={this.onCreate}
                display={this.handleDisplay}
            />
        );
    }
}

PostCrudList.propTypes = {
    items: PropTypes.array.isRequired,
    updateItems: PropTypes.func.isRequired
};

export default PostCrudList;